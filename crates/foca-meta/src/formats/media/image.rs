//! JPEG/PNG/TIFF images: EXIF (camera, serial numbers, software, dates, GPS in decimal degrees,
//! IFD1 thumbnail), XMP, IPTC (JPEG APP13), PNG text chunks and JPEG comments.

use std::io::{Cursor, Read};

use exif::{Context, Field, In, Tag, Value};
use foca_core::{Camera, DocFormat, Gps, Metadata, PersonRole, Thumbnail};

use super::image_extra;
use crate::util::{clean_str, normalize_date, truncate, utf16le_z};
use crate::{xmp, Ctx, MetaError};

/// Returns JPEG segments before SOS as (marker, segment start at 0xFF, data start, data end).
pub(crate) fn jpeg_segments(b: &[u8]) -> Vec<(u8, usize, usize, usize)> {
    let mut out = Vec::new();
    if !b.starts_with(&[0xFF, 0xD8]) {
        return out;
    }
    let mut p = 2;
    while p + 1 < b.len() && out.len() < 10_000 {
        if b[p] != 0xFF {
            break;
        }
        let mut q = p + 1;
        while q < b.len() && b[q] == 0xFF {
            q += 1;
        }
        let Some(&m) = b.get(q) else { break };
        if (0xD0..=0xD7).contains(&m) || m == 0x01 {
            out.push((m, p, q + 1, q + 1));
            p = q + 1;
            continue;
        }
        if m == 0xD9 {
            out.push((m, p, q + 1, q + 1));
            break;
        }
        let Some(len) = b
            .get(q + 1..q + 3)
            .map(|s| usize::from(u16::from_be_bytes([s[0], s[1]])))
        else {
            break;
        };
        if len < 2 {
            break;
        }
        let start = q + 3;
        let end = (q + 1 + len).min(b.len());
        out.push((m, p, start, end));
        if m == 0xDA {
            break;
        }
        p = q + 1 + len;
    }
    out
}

fn ascii(f: &Field) -> Option<String> {
    match &f.value {
        Value::Ascii(v) => {
            let s: Vec<String> = v
                .iter()
                .map(|x| {
                    String::from_utf8_lossy(x)
                        .trim_matches(char::from(0))
                        .trim()
                        .to_string()
                })
                .filter(|x| !x.is_empty())
                .collect();
            clean_str(&s.join(" "))
        }
        Value::Byte(b) | Value::Undefined(b, _) => {
            // XP* tags are UTF-16LE
            if f.tag.number() >= 0x9C9B && f.tag.number() <= 0x9C9F {
                clean_str(&utf16le_z(b))
            } else if b.starts_with(b"ASCII\0\0\0") {
                clean_str(&String::from_utf8_lossy(&b[8..]))
            } else if b.starts_with(b"UNICODE\0") {
                clean_str(&utf16le_z(&b[8..]))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn rational3(f: &Field) -> Option<f64> {
    if let Value::Rational(v) = &f.value {
        let mut deg = 0.0;
        for (i, r) in v.iter().take(3).enumerate() {
            if r.denom == 0 {
                return None;
            }
            deg += r.to_f64() / [1.0, 60.0, 3600.0][i];
        }
        if deg.is_finite() {
            return Some(deg);
        }
    }
    None
}

/// Applies a raw TIFF/EXIF block (as stored in HEIF `Exif` items) to `meta`, including the
/// embedded XMP (tag 700). Returns `false` if the block cannot be parsed.
pub(crate) fn apply_exif_tiff(meta: &mut Metadata, tiff: Vec<u8>, ctx: &Ctx) -> bool {
    let Ok(Some(ex)) = crate::guard("exif", || Ok(exif::Reader::new().read_raw(tiff).ok())) else {
        return false;
    };
    exif_meta(meta, &ex);
    if let Some(f) = ex.get_field(Tag(Context::Tiff, 700), In::PRIMARY) {
        if let Value::Byte(x) | Value::Undefined(x, _) = &f.value {
            let map = xmp::parse(x, ctx);
            xmp::apply(meta, &map, "xmp");
        }
    }
    true
}

fn exif_meta(meta: &mut Metadata, ex: &exif::Exif) {
    let get = |t: Tag| ex.get_field(t, In::PRIMARY);
    let s = |t: Tag| get(t).and_then(ascii);
    let mut cam = Camera {
        make: s(Tag::Make),
        model: s(Tag::Model),
        serial: s(Tag::BodySerialNumber).or_else(|| s(Tag(Context::Exif, 0xA431))),
        lens: s(Tag::LensModel),
        lens_serial: s(Tag::LensSerialNumber),
        owner: s(Tag::CameraOwnerName),
    };
    // some vendors store the serial number in non-standard tags
    if cam.serial.is_none() {
        cam.serial = s(Tag(Context::Tiff, 0xC62F)); // CameraSerialNumber (DNG)
    }
    if let Some(o) = &cam.owner {
        meta.add_person(o, PersonRole::Owner, "exif:CameraOwnerName");
    }
    if cam != Camera::default() {
        meta.camera = Some(cam);
    }
    if let Some(sw) = s(Tag::Software) {
        Metadata::add_unique(&mut meta.software, &sw);
        meta.application = Some(sw);
    }
    if let Some(a) = s(Tag::Artist) {
        meta.add_person(&a, PersonRole::Author, "exif:Artist");
        meta.author = Some(a);
    }
    if let Some(a) = s(Tag(Context::Tiff, 0x9C9D)) {
        meta.add_person(&a, PersonRole::Author, "exif:XPAuthor");
        meta.author.get_or_insert(a);
    }
    if let Some(h) = s(Tag(Context::Tiff, 0x013C)) {
        meta.add_server(&h, "exif:HostComputer");
    }
    meta.description = s(Tag::ImageDescription).or_else(|| s(Tag(Context::Tiff, 0x9C9C)));
    meta.title = s(Tag(Context::Tiff, 0x9C9B));
    meta.keywords = s(Tag(Context::Tiff, 0x9C9E));
    meta.subject = s(Tag(Context::Tiff, 0x9C9F));
    meta.created = ex
        .get_field(Tag::DateTimeOriginal, In::PRIMARY)
        .and_then(ascii)
        .and_then(|d| normalize_date(&d));
    meta.modified = s(Tag::DateTime).and_then(|d| normalize_date(&d));
    if meta.created.is_none() {
        meta.created = s(Tag::DateTimeDigitized).and_then(|d| normalize_date(&d));
    }
    // GPS
    let lat = get(Tag::GPSLatitude).and_then(rational3);
    let lon = get(Tag::GPSLongitude).and_then(rational3);
    if let (Some(mut lat), Some(mut lon)) = (lat, lon) {
        if s(Tag::GPSLatitudeRef).is_some_and(|r| r.eq_ignore_ascii_case("S")) {
            lat = -lat;
        }
        if s(Tag::GPSLongitudeRef).is_some_and(|r| r.eq_ignore_ascii_case("W")) {
            lon = -lon;
        }
        let alt = get(Tag::GPSAltitude).and_then(|f| match &f.value {
            Value::Rational(v) if v.first().is_some_and(|r| r.denom != 0) => {
                v.first().map(|r| r.to_f64())
            }
            _ => None,
        });
        let below = get(Tag::GPSAltitudeRef)
            .is_some_and(|f| matches!(&f.value, Value::Byte(b) if b.first() == Some(&1)));
        let alt = alt.map(|a| if below { -a } else { a });
        if (-90.0..=90.0).contains(&lat)
            && (-180.0..=180.0).contains(&lon)
            && !(lat == 0.0 && lon == 0.0)
        {
            let r = |x: f64| (x * 1e6).round() / 1e6;
            meta.gps = Some(Gps {
                lat: r(lat),
                lon: r(lon),
                alt: alt.map(|a| (a * 100.0).round() / 100.0),
            });
        }
    }
    // thumbnail
    let off = ex
        .get_field(Tag::JPEGInterchangeFormat, In::THUMBNAIL)
        .and_then(|f| f.value.get_uint(0));
    let len = ex
        .get_field(Tag::JPEGInterchangeFormatLength, In::THUMBNAIL)
        .and_then(|f| f.value.get_uint(0));
    if let (Some(o), Some(l)) = (off, len) {
        let (o, l) = (o as usize, l as usize);
        if let Some(t) = o.checked_add(l).and_then(|e| ex.buf().get(o..e)) {
            if t.starts_with(&[0xFF, 0xD8]) {
                meta.thumbnail = Some(Thumbnail {
                    mime: "image/jpeg".into(),
                    data: t.to_vec(),
                    differs: None,
                });
            }
        }
    }
    // raw fields
    for f in ex.fields() {
        if f.ifd_num != In::PRIMARY {
            continue;
        }
        let n = f.tag.number();
        if matches!(
            f.tag,
            Tag::MakerNote | Tag::ExifIFDPointer | Tag::GPSInfoIFDPointer | Tag::InteropIFDPointer
        ) || n == 700
            || n == 0x8773
            || n == 0x83BB
        {
            continue;
        }
        let v = match ascii(f) {
            Some(v) => v,
            None => match &f.value {
                Value::Undefined(b, _) | Value::Byte(b) if b.len() > 64 => continue,
                _ => f.display_value().with_unit(ex).to_string(),
            },
        };
        meta.fields
            .insert(format!("exif:{}", f.tag), truncate(&v, 256));
    }
    // XMP in TIFF (tag 700)
}

fn iptc(meta: &mut Metadata, data: &[u8]) {
    // "Photoshop 3.0\0" followed by 8BIM blocks; resource 0x0404 is IPTC-NAA
    let mut p = 14;
    while p + 12 <= data.len() {
        if &data[p..p + 4] != b"8BIM" {
            break;
        }
        let id = u16::from_be_bytes([data[p + 4], data[p + 5]]);
        let nlen = usize::from(data[p + 6]);
        let mut q = p + 7 + nlen;
        if (1 + nlen) % 2 == 1 {
            q += 1;
        }
        let Some(sz) = data
            .get(q..q + 4)
            .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as usize)
        else {
            break;
        };
        let start = q + 4;
        let Some(end) = start.checked_add(sz).filter(|e| *e <= data.len()) else {
            break;
        };
        if id == 0x0404 {
            iptc_records(meta, &data[start..end]);
        }
        p = end + (sz % 2);
    }
}

fn iptc_records(meta: &mut Metadata, d: &[u8]) {
    let mut p = 0;
    let mut kw = Vec::new();
    while p + 5 <= d.len() && d[p] == 0x1C {
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
        if rec != 2 {
            continue;
        }
        let Some(s) = clean_str(&crate::util::decode_text(v)) else {
            continue;
        };
        let key = match ds {
            5 => "ObjectName",
            25 => {
                kw.push(s.clone());
                "Keywords"
            }
            65 => "OriginatingProgram",
            80 => "By-line",
            85 => "By-lineTitle",
            90 => "City",
            95 => "Province-State",
            101 => "Country",
            105 => "Headline",
            110 => "Credit",
            115 => "Source",
            116 => "CopyrightNotice",
            118 => "Contact",
            120 => "Caption-Abstract",
            122 => "Writer-Editor",
            _ => continue,
        };
        match ds {
            80 => {
                meta.add_person(&s, PersonRole::Author, "iptc:By-line");
                meta.author.get_or_insert(s.clone());
            }
            122 => meta.add_person(&s, PersonRole::Other, "iptc:Writer-Editor"),
            65 => Metadata::add_unique(&mut meta.software, &s),
            105 => {
                meta.title.get_or_insert(s.clone());
            }
            120 => {
                meta.description.get_or_insert(s.clone());
            }
            _ => {}
        }
        if ds != 25 {
            meta.fields.insert(format!("iptc:{key}"), truncate(&s, 512));
        }
    }
    if !kw.is_empty() {
        meta.fields.insert("iptc:Keywords".into(), kw.join(", "));
        meta.keywords.get_or_insert(kw.join(", "));
    }
}

fn png_chunks(meta: &mut Metadata, b: &[u8], ctx: &Ctx) -> Result<(), MetaError> {
    let mut p = 8;
    let mut n = 0;
    while p + 12 <= b.len() && n < 10_000 {
        n += 1;
        let len = u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]) as usize;
        let ty = &b[p + 4..p + 8];
        let Some(data) = (p + 8).checked_add(len).and_then(|e| b.get(p + 8..e)) else {
            break;
        };
        p = p + 12 + len;
        let (key, text): (String, Option<String>) = match ty {
            b"tEXt" => {
                let z = data.iter().position(|&c| c == 0).unwrap_or(data.len());
                (
                    crate::util::decode_codepage(&data[..z], 28591),
                    Some(crate::util::decode_codepage(
                        data.get(z + 1..).unwrap_or(&[]),
                        28591,
                    )),
                )
            }
            b"zTXt" | b"iTXt" => {
                let z = data.iter().position(|&c| c == 0).unwrap_or(data.len());
                let key = String::from_utf8_lossy(&data[..z]).into_owned();
                let rest = data.get(z + 1..).unwrap_or(&[]);
                let (compressed, payload) = if ty == b"zTXt" {
                    (true, rest.get(1..).unwrap_or(&[]))
                } else {
                    let comp = rest.first() == Some(&1);
                    let r = rest.get(2..).unwrap_or(&[]);
                    let l1 = r
                        .iter()
                        .position(|&c| c == 0)
                        .map(|i| i + 1)
                        .unwrap_or(r.len());
                    let r = r.get(l1..).unwrap_or(&[]);
                    let l2 = r
                        .iter()
                        .position(|&c| c == 0)
                        .map(|i| i + 1)
                        .unwrap_or(r.len());
                    (comp, r.get(l2..).unwrap_or(&[]))
                };
                let raw = if compressed {
                    let cap = ctx.remaining().min(16 << 20);
                    let mut out = Vec::new();
                    let _ = flate2::read::ZlibDecoder::new(payload)
                        .take(cap + 1)
                        .read_to_end(&mut out);
                    if out.len() as u64 > cap {
                        return Err(MetaError::ZipBomb(
                            "PNG: текстовый чанк больше лимита".into(),
                        ));
                    }
                    ctx.spend(out.len() as u64)?;
                    out
                } else {
                    payload.to_vec()
                };
                let s = if ty == b"zTXt" {
                    crate::util::decode_codepage(&raw, 28591)
                } else {
                    String::from_utf8_lossy(&raw).into_owned()
                };
                (key, Some(s))
            }
            b"iCCP" => {
                image_extra::png_iccp(meta, data, ctx)?;
                continue;
            }
            b"caBX" => {
                image_extra::c2pa(meta, data);
                continue;
            }
            b"IEND" => break,
            _ => continue,
        };
        let Some(text) = text else { continue };
        // generator prompts stay out of plain fields (shown on the document card only)
        if image_extra::is_generator_key(&key) && image_extra::png_generator(meta, &key, &text) {
            continue;
        }
        if key == "XML:com.adobe.xmp" {
            let map = xmp::parse(text.as_bytes(), ctx);
            xmp::apply(meta, &map, "xmp");
            continue;
        }
        let Some(v) = clean_str(&text) else { continue };
        match key.as_str() {
            "Author" => {
                meta.add_person(&v, PersonRole::Author, "png:Author");
                meta.author.get_or_insert(v.clone());
            }
            "Software" => {
                Metadata::add_unique(&mut meta.software, &v);
                meta.application.get_or_insert(v.clone());
            }
            "Title" => {
                meta.title.get_or_insert(v.clone());
            }
            "Description" => {
                meta.description.get_or_insert(v.clone());
            }
            "Creation Time" => {
                meta.created.get_or_insert(v.clone());
            }
            _ => {}
        }
        meta.fields.insert(format!("png:{key}"), truncate(&v, 1024));
    }
    Ok(())
}

/// Camera maker note (Canon, Nikon, Fujifilm, Apple) through the raw EXIF TIFF block.
fn maker_note(meta: &mut Metadata, ex: &exif::Exif) {
    let Some(f) = ex.get_field(Tag::MakerNote, In::PRIMARY) else {
        return;
    };
    let Value::Undefined(_, off) = &f.value else {
        return;
    };
    let make = meta
        .camera
        .as_ref()
        .and_then(|c| c.make.clone())
        .unwrap_or_default();
    image_extra::maker_note(meta, &make, ex.buf(), *off as usize, ex.little_endian());
}

pub fn extract(b: &[u8], format: DocFormat, ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut meta = Metadata::new(format);
    let ex = crate::guard("exif", || {
        Ok(exif::Reader::new()
            .read_from_container(&mut Cursor::new(b))
            .ok())
    })?;
    if let Some(ex) = &ex {
        exif_meta(&mut meta, ex);
        maker_note(&mut meta, ex);
        if let Some(f) = ex.get_field(Tag(Context::Tiff, 700), In::PRIMARY) {
            if let Value::Byte(x) | Value::Undefined(x, _) = &f.value {
                let map = xmp::parse(x, ctx);
                xmp::apply(&mut meta, &map, "xmp");
            }
        }
    }
    match format {
        DocFormat::Jpeg => {
            let mut icc_profile: Vec<u8> = Vec::new();
            let mut jumbf: Vec<u8> = Vec::new();
            for (m, _, s, e) in jpeg_segments(b) {
                let Some(data) = b.get(s..e) else { continue };
                match m {
                    0xE2 if data.starts_with(b"ICC_PROFILE\0") && icc_profile.len() < (4 << 20) => {
                        icc_profile.extend_from_slice(data.get(14..).unwrap_or(&[]));
                    }
                    0xEB if data.starts_with(b"JP") && jumbf.len() < (8 << 20) => {
                        jumbf.extend_from_slice(data);
                    }
                    0xE1 if data.starts_with(b"http://ns.adobe.com/xap/1.0/\0") => {
                        let map = xmp::parse(&data[29..], ctx);
                        xmp::apply(&mut meta, &map, "xmp");
                    }
                    0xED if data.starts_with(b"Photoshop 3.0\0") => iptc(&mut meta, data),
                    0xFE => {
                        if let Some(c) = clean_str(&crate::util::decode_text(data)) {
                            meta.fields
                                .insert("jpeg:comment".into(), truncate(&c, 1024));
                        }
                    }
                    _ => {}
                }
            }
            image_extra::icc(&mut meta, &icc_profile);
            image_extra::c2pa(&mut meta, &jumbf);
        }
        DocFormat::Png => png_chunks(&mut meta, b, ctx)?,
        _ => {}
    }
    image_extra::xmp_ai(&mut meta);
    // Compare thumbnail and photo pixels; a decoder panic on a broken file must not abort parsing.
    if format == DocFormat::Jpeg {
        if let Some(t) = meta.thumbnail.as_mut() {
            t.differs = std::panic::catch_unwind(|| crate::thumbcmp::thumbnail_differs(b, &t.data))
                .ok()
                .flatten();
        }
    }
    if ex.is_none() && meta.xmp.is_empty() && meta.fields.is_empty() {
        // no metadata is not an error
    }
    Ok(meta)
}

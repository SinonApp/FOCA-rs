//! Format detection by signature; file extensions are not trusted.

use std::cell::Cell;
use std::io::Cursor;

use foca_core::DocFormat;

use crate::util::decode_text;
use crate::zipx::SafeZip;
use crate::{Ctx, Limits};

/// 6-byte magic signature of a 7z archive (`'7', 'z', 0xBC, 0xAF, 0x27, 0x1C`).
pub(crate) const SEVENZ_MAGIC: [u8; 6] = [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];

/// Detects the document format from its content.
pub fn detect(bytes: &[u8]) -> DocFormat {
    detect_with_hint(bytes, None)
}

pub(crate) fn detect_with_hint(bytes: &[u8], name_hint: Option<&str>) -> DocFormat {
    let b = bytes;
    if b.starts_with(b"PK\x03\x04") {
        return detect_zip(b);
    }
    if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return DocFormat::Jpeg;
    }
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        return DocFormat::Png;
    }
    if b.starts_with(b"II*\0") || b.starts_with(b"MM\0*") {
        return DocFormat::Tiff;
    }
    if b.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return detect_ole(b);
    }
    if crate::formats::binary::pe::is_pe(b) {
        return DocFormat::Exe;
    }
    if let Some(f) = detect_new_binary(b, name_hint) {
        return f;
    }
    if b.starts_with(&crate::formats::lnk::MAGIC) {
        return DocFormat::Lnk;
    }
    if b.starts_with(&crate::formats::media::indesign::MAGIC) {
        return DocFormat::Indd;
    }
    if b.starts_with(crate::formats::office::legacy_office::WPD_MAGIC) {
        return DocFormat::Wpd;
    }
    if b.starts_with(b"8BPS\x00\x01") || b.starts_with(b"8BPS\x00\x02") {
        return DocFormat::Psd;
    }
    if b.starts_with(&SEVENZ_MAGIC) {
        return DocFormat::SevenZ;
    }
    if crate::formats::media::mp3::is_mp3(b) {
        return DocFormat::Mp3;
    }
    if let Some(f) = crate::formats::media::isobmff::brand_format(b) {
        return f;
    }
    let ext = ext_of(name_hint);
    if crate::formats::office::legacy_office::is_lotus_wks(b) && ext == "wks" {
        return DocFormat::Wks;
    }
    // QuickTime files without `ftyp` start with a movie-level atom
    if matches!(
        b.get(4..8),
        Some(b"moov" | b"mdat" | b"wide" | b"free" | b"skip")
    ) && matches!(ext.as_str(), "mov" | "qt" | "mp4" | "m4v" | "3gp")
    {
        return DocFormat::Mov;
    }
    // %PDF may be preceded by up to 1024 bytes of garbage
    let head = &b[..b.len().min(1024)];
    if head.windows(5).any(|w| w == b"%PDF-") {
        return DocFormat::Pdf;
    }
    detect_text(b, name_hint)
}

/// Signatures of the executable, archive, CAD, PostScript and audio/video formats.
fn detect_new_binary(b: &[u8], name_hint: Option<&str>) -> Option<DocFormat> {
    use crate::formats::magic;
    use crate::formats::media::{av, postscript};
    if b.starts_with(magic::RAR4) || b.starts_with(magic::RAR5) {
        return Some(DocFormat::Rar);
    }
    if b.starts_with(&magic::GZIP_MAGIC) {
        return Some(DocFormat::Gzip);
    }
    if magic::is_bzip2(b) {
        return Some(DocFormat::Bzip2);
    }
    if b.starts_with(&magic::XZ_MAGIC) {
        return Some(DocFormat::Xz);
    }
    if b.starts_with(&av::ASF_HEADER) {
        return Some(DocFormat::Asf);
    }
    if b.starts_with(&av::EBML_MAGIC) {
        return Some(DocFormat::Mkv);
    }
    if b.starts_with(b"fLaC") {
        return Some(DocFormat::Flac);
    }
    if b.starts_with(b"OggS") {
        return Some(DocFormat::Ogg);
    }
    if let Some(f) = av::riff_kind(b) {
        return Some(f);
    }
    if crate::formats::cad::is_dwg(b) {
        return Some(DocFormat::Dwg);
    }
    if postscript::is_postscript(b) {
        return Some(DocFormat::Eps);
    }
    if postscript::is_emf(b) {
        return Some(DocFormat::Emf);
    }
    let ext = ext_of(name_hint);
    if b.starts_with(&[0xD7, 0xCD, 0xC6, 0x9A]) || (postscript::is_wmf(b) && ext == "wmf") {
        return Some(DocFormat::Wmf);
    }
    if magic::is_tar(b)
        && (b.get(257..262) == Some(b"ustar") || matches!(ext.as_str(), "tar" | "tgz"))
    {
        return Some(DocFormat::Tar);
    }
    None
}

fn detect_zip(b: &[u8]) -> DocFormat {
    let Ok(mut z) = SafeZip::open(b, 100_000) else {
        return DocFormat::Unknown;
    };
    let names: Vec<String> = z.names().to_vec();
    let has = |n: &str| names.iter().any(|x| x == n);
    if has("word/document.xml") {
        return DocFormat::Docx;
    }
    if has("xl/workbook.xml") {
        return DocFormat::Xlsx;
    }
    if has("ppt/presentation.xml") {
        return DocFormat::Pptx;
    }
    if has("[Content_Types].xml") {
        // non-standard names of the main part
        let prefix = |p: &str| names.iter().any(|x| x.starts_with(p));
        if prefix("word/") {
            return DocFormat::Docx;
        }
        if prefix("xl/") {
            return DocFormat::Xlsx;
        }
        if prefix("ppt/") {
            return DocFormat::Pptx;
        }
    }
    if has("mimetype") {
        let limits = Limits::default();
        let budget = Cell::new(4096);
        let ctx = Ctx::standalone(&limits, &budget);
        if let Ok(Some(m)) = z.read_prefix("mimetype", 200, &ctx) {
            let m = String::from_utf8_lossy(&m);
            let m = m.trim();
            return match m {
                "application/vnd.oasis.opendocument.text"
                | "application/vnd.oasis.opendocument.text-template" => DocFormat::Odt,
                "application/vnd.oasis.opendocument.spreadsheet"
                | "application/vnd.oasis.opendocument.spreadsheet-template" => DocFormat::Ods,
                "application/vnd.oasis.opendocument.presentation"
                | "application/vnd.oasis.opendocument.presentation-template" => DocFormat::Odp,
                "application/vnd.oasis.opendocument.graphics" => DocFormat::Odg,
                "application/epub+zip" => DocFormat::Epub,
                s if s.starts_with("application/vnd.sun.xml.") => DocFormat::Sxw,
                s if s.starts_with("application/vnd.oasis.opendocument.") => DocFormat::Odt,
                _ => DocFormat::Unknown,
            };
        }
    }
    if has("META-INF/container.xml") {
        return DocFormat::Epub;
    }
    if has("meta.xml") && has("content.xml") {
        return DocFormat::Odt;
    }
    if has("visio/document.xml") {
        return DocFormat::Vsdx;
    }
    if let Some(f) = crate::formats::binary::jar::zip_kind(&names) {
        return f;
    }
    if crate::formats::geo::is_kmz(&names) {
        return DocFormat::Kmz;
    }
    // any other readable archive is parsed as a plain ZIP with recursive members
    DocFormat::Zip
}

fn detect_ole(b: &[u8]) -> DocFormat {
    let r = crate::guard("ole", || {
        let cf = cfb::CompoundFile::open(Cursor::new(b))
            .map_err(|e| crate::MetaError::malformed("ole", e))?;
        let mut names = Vec::new();
        for e in cf.read_root_storage() {
            names.push(e.name().to_string());
        }
        Ok((names, cf.root_entry().clsid().to_string()))
    });
    let Ok((names, clsid)) = r else {
        return DocFormat::Ole;
    };
    // Windows Installer package, patch and transform
    if matches!(
        clsid.as_str(),
        "000c1084-0000-0000-c000-000000000046"
            | "000c1086-0000-0000-c000-000000000046"
            | "000c1082-0000-0000-c000-000000000046"
    ) {
        return DocFormat::Msi;
    }
    let has = |n: &str| names.iter().any(|x| x.eq_ignore_ascii_case(n));
    if crate::formats::mail::msg::is_msg(&names) {
        return DocFormat::Msg;
    }
    if has("VisioDocument") {
        return DocFormat::Vsd;
    }
    if crate::formats::office::publisher::is_pub(&names) {
        return DocFormat::Pub;
    }
    if let Some(f) = crate::formats::office::legacy_office::works_format(&names) {
        return f;
    }
    if has("WordDocument") {
        DocFormat::Doc
    } else if has("Workbook") || has("Book") {
        DocFormat::Xls
    } else if has("PowerPoint Document") {
        DocFormat::Ppt
    } else {
        DocFormat::Ole
    }
}

fn detect_text(b: &[u8], name_hint: Option<&str>) -> DocFormat {
    if b.is_empty() {
        return DocFormat::Unknown;
    }
    let head = decode_text(&b[..b.len().min(8192)]);
    // binary data is not text
    let ctrl = head
        .chars()
        .filter(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        .count();
    if ctrl * 20 > head.chars().count().max(1) {
        return DocFormat::Unknown;
    }
    let lower = head.to_ascii_lowercase();
    let ext = ext_of(name_hint);
    let start = lower.trim_start_matches('\u{feff}').trim_start();
    if start.starts_with("begin:vcalendar") {
        return DocFormat::Ics;
    }
    if start.starts_with("begin:vcard") {
        return DocFormat::Vcf;
    }
    if crate::formats::dev::looks_like_sourcemap(&head) {
        return DocFormat::SourceMap;
    }
    if crate::formats::dev::looks_like_notebook(&head) {
        return DocFormat::Ipynb;
    }
    if crate::formats::cad::looks_like_dxf(&head) {
        return DocFormat::Dxf;
    }
    if lower.contains("<kml") {
        return DocFormat::Kml;
    }
    if lower.contains("<gpx") {
        return DocFormat::Gpx;
    }
    if crate::formats::mail::eml::looks_like_mail(&head, &ext) {
        return DocFormat::Eml;
    }
    if lower.contains("<svg") {
        return DocFormat::Svg;
    }
    let rdp_like = lower.lines().filter(|l| is_rdp_line(l)).count();
    let ica_like = lower.contains("[wfclient]") || lower.contains("[applicationservers]");
    if ica_like && (ext == "ica" || rdp_like == 0) {
        return DocFormat::Ica;
    }
    if rdp_like >= 1 && (lower.contains("full address:s:") || ext == "rdp" || rdp_like >= 3) {
        return DocFormat::Rdp;
    }
    if ica_like {
        return DocFormat::Ica;
    }
    DocFormat::Unknown
}

/// Returns the lower-cased extension of a file name hint.
fn ext_of(name_hint: Option<&str>) -> String {
    name_hint
        .and_then(|n| n.rsplit_once('.'))
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default()
}

/// Returns `true` for an RDP line of the form `key:t:value`, where t is one of `s`, `i`, `b`.
fn is_rdp_line(l: &str) -> bool {
    let mut it = l.trim().splitn(3, ':');
    match (it.next(), it.next(), it.next()) {
        (Some(k), Some(t), Some(_)) => !k.is_empty() && matches!(t, "s" | "i" | "b"),
        _ => false,
    }
}

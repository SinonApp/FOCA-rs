//! AutoCAD drawings: DWG (binary) and DXF (text).
//!
//! DWG: version and codepage from the file header; the paged/compressed sections of R2004+ are
//! not decoded, but the uncompressed AppInfo and FileDepList pages are stored raw, so readable
//! ASCII/UTF-16 strings give the writing application, xref/image/font file paths and the user
//! names inside those paths. DXF: header variables (`$ACADVER`, `$TDCREATE`, `$TDUPDATE`,
//! `$LASTSAVEDBY`, `$HYPERLINKBASE`, `$PROJECTNAME`) and every path-like group value (xrefs,
//! image definitions, fonts, plot styles).

use foca_core::{DocFormat, Metadata, PersonRole};

use crate::util::{clean_str, decode_text, rd_u16le, truncate};
use crate::{Ctx, MetaError};

const MAX_SCAN: usize = 32 << 20;

pub(crate) fn is_dwg(b: &[u8]) -> bool {
    b.len() >= 6 && b.starts_with(b"AC10") && b[4..6].iter().all(u8::is_ascii_digit)
}

fn release(code: &str) -> Option<&'static str> {
    Some(match code {
        "AC1006" => "R10",
        "AC1009" => "R11/R12",
        "AC1012" => "R13",
        "AC1014" => "R14",
        "AC1015" => "AutoCAD 2000",
        "AC1018" => "AutoCAD 2004",
        "AC1021" => "AutoCAD 2007",
        "AC1024" => "AutoCAD 2010",
        "AC1027" => "AutoCAD 2013",
        "AC1032" => "AutoCAD 2018",
        _ => return None,
    })
}

pub fn extract_dwg(b: &[u8], _ctx: &Ctx) -> Result<Metadata, MetaError> {
    crate::guard("dwg", || {
        if !is_dwg(b) {
            return Err(MetaError::malformed("dwg", "нет сигнатуры AC10xx"));
        }
        let mut meta = Metadata::new(DocFormat::Dwg);
        let code = String::from_utf8_lossy(&b[..6]).into_owned();
        meta.fields.insert("dwg:version".into(), code.clone());
        if let Some(r) = release(&code) {
            meta.fields.insert("dwg:release".into(), r.into());
        }
        if let Some(cp) = rd_u16le(b, 0x13) {
            meta.fields.insert("dwg:codepage".into(), cp.to_string());
        }
        let scan = &b[..b.len().min(MAX_SCAN)];
        let mut strings = ascii_strings(scan, 6, 4000);
        strings.extend(utf16_strings(scan, 5, 4000));
        let mut paths = 0;
        for s in &strings {
            if let Some(p) = product_info(s) {
                Metadata::add_unique(&mut meta.software, &p);
                meta.application.get_or_insert(p);
            }
            for p in crate::paths::find_paths(s) {
                if paths < 200 && crate::paths::add_path(&mut meta, &p, "dwg:filedep") {
                    paths += 1;
                }
            }
        }
        if paths > 0 {
            meta.stats.insert("dependency_paths".into(), paths);
        }
        meta.warnings
            .push("DWG: сжатые разделы (SummaryInfo) не разбираются".into());
        Ok(meta)
    })
}

/// `<ProductInformation name ="AutoCAD" build_version="..." .../>` from AcDb:AppInfo.
fn product_info(s: &str) -> Option<String> {
    let i = s.find("ProductInformation")?;
    let rest = &s[i..];
    let attr = |k: &str| -> Option<String> {
        let at = rest.find(k)? + k.len();
        let r = rest[at..].trim_start().strip_prefix('=')?.trim_start();
        let r = r.strip_prefix('"')?;
        Some(r[..r.find('"')?].to_string())
    };
    let name = attr("name")?;
    Some(match attr("build_version") {
        Some(v) => format!("{name} {v}"),
        None => name,
    })
}

pub(crate) fn ascii_strings(b: &[u8], min: usize, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &c) in b.iter().enumerate() {
        let printable = (0x20..0x7F).contains(&c);
        match (printable, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min && out.len() < max {
                    out.push(String::from_utf8_lossy(&b[s..i.min(s + 2048)]).into_owned());
                }
                start = None;
            }
            _ => {}
        }
    }
    out
}

pub(crate) fn utf16_strings(b: &[u8], min: usize, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    for phase in 0..2 {
        let mut cur: Vec<u16> = Vec::new();
        let mut i = phase;
        while i + 1 < b.len() {
            let c = u16::from_le_bytes([b[i], b[i + 1]]);
            let ok = (0x20..0x7F).contains(&c) || (0x400..0x500).contains(&c);
            if ok && cur.len() < 2048 {
                cur.push(c);
            } else {
                if cur.len() >= min && out.len() < max {
                    out.push(String::from_utf16_lossy(&cur));
                }
                cur.clear();
            }
            i += 2;
        }
    }
    out
}

/// Returns `true` for DXF text: group code / value line pairs starting with `0 SECTION`.
pub(crate) fn looks_like_dxf(head: &str) -> bool {
    let mut lines = head.lines().map(str::trim).filter(|l| !l.is_empty());
    let first_is_999 = head.trim_start().starts_with("999");
    let mut lines2 = lines.clone();
    if first_is_999 {
        lines2.next();
        lines2.next();
        lines = lines2;
    }
    lines.next() == Some("0") && lines.next() == Some("SECTION")
}

/// AutoCAD Julian date (days.fraction) -> ISO 8601 without an offset (drawing local time).
fn julian(v: &str) -> Option<String> {
    let jd: f64 = v.trim().parse().ok()?;
    if !(2_400_000.0..2_600_000.0).contains(&jd) {
        return None;
    }
    let secs = ((jd - 2_440_587.5) * 86_400.0).round() as i64;
    let t = time::OffsetDateTime::from_unix_timestamp(secs).ok()?;
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    ))
}

pub fn extract_dxf(b: &[u8], _ctx: &Ctx) -> Result<Metadata, MetaError> {
    crate::guard("dxf", || {
        let text = decode_text(&b[..b.len().min(MAX_SCAN)]);
        let mut meta = Metadata::new(DocFormat::Dxf);
        let mut lines = text.lines();
        let mut var: Option<String> = None;
        let mut pairs = 0usize;
        let mut paths = 0u64;
        while let (Some(code), Some(value)) = (lines.next(), lines.next()) {
            pairs += 1;
            if pairs > 2_000_000 {
                meta.warnings.push("DXF: файл обрезан при разборе".into());
                break;
            }
            let code = code.trim();
            let value = value.trim_end_matches('\r');
            if code == "9" {
                var = Some(value.trim().to_string());
                continue;
            }
            if let Some(v) = var.take() {
                header_var(&mut meta, &v, code, value);
            }
            if matches!(
                code,
                "1" | "3" | "300" | "301" | "302" | "303" | "304" | "1000"
            ) && paths < 200
            {
                for p in crate::paths::find_paths(value) {
                    if crate::paths::add_path(&mut meta, &p, "dxf:path") {
                        paths += 1;
                    }
                }
            }
            if code == "999" {
                if let Some(c) = clean_str(value) {
                    meta.fields
                        .entry("dxf:comment".into())
                        .or_insert(truncate(&c, 512));
                }
            }
        }
        if paths > 0 {
            meta.stats.insert("dependency_paths".into(), paths);
        }
        Ok(meta)
    })
}

fn header_var(meta: &mut Metadata, var: &str, _code: &str, value: &str) {
    let Some(v) = clean_str(value) else { return };
    let v = truncate(&v, 512);
    match var {
        "$ACADVER" => {
            if let Some(r) = release(&v) {
                meta.fields.insert("dxf:release".into(), r.into());
                Metadata::add_unique(&mut meta.software, r);
            }
            meta.fields.insert("dxf:version".into(), v);
        }
        "$TDCREATE" => meta.created = julian(&v),
        "$TDUPDATE" => meta.modified = julian(&v),
        "$LASTSAVEDBY" => {
            meta.add_person(&v, PersonRole::LastModifiedBy, "dxf:$LASTSAVEDBY");
            meta.last_modified_by = Some(v);
        }
        "$HYPERLINKBASE" | "$PROJECTNAME" | "$FINGERPRINTGUID" | "$VERSIONGUID" | "$MENU"
        | "$DWGCODEPAGE" => {
            meta.fields
                .insert(format!("dxf:{}", var.trim_start_matches('$')), v);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn julian_dates() {
        assert_eq!(julian("2440587.5").as_deref(), Some("1970-01-01T00:00:00"));
        assert!(julian("abc").is_none());
    }

    #[test]
    fn product_info_attr() {
        assert_eq!(
            product_info(r#"<ProductInformation name ="AutoCAD" build_version="R.47.0.0" />"#)
                .as_deref(),
            Some("AutoCAD R.47.0.0")
        );
    }
}
